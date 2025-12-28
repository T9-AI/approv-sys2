(function(){
  function setupCanvas(canvas, outputInput, clearBtn){
    if(!canvas) return;

    const ctx = canvas.getContext("2d");
    let drawing = false;
    let lastX = 0, lastY = 0;

    function resizeForHiDPI(){
      // keep crisp lines
      const rect = canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      canvas.width = Math.round(rect.width * dpr);
      canvas.height = Math.round(rect.height * dpr);
      ctx.setTransform(dpr,0,0,dpr,0,0);

      // style
      ctx.lineWidth = 2.2;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.strokeStyle = "#111827";
    }

    function getPos(e){
      const rect = canvas.getBoundingClientRect();
      const t = (e.touches && e.touches[0]) ? e.touches[0] : null;
      const clientX = t ? t.clientX : e.clientX;
      const clientY = t ? t.clientY : e.clientY;
      return {
        x: clientX - rect.left,
        y: clientY - rect.top
      };
    }

    function start(e){
      e.preventDefault();
      drawing = true;
      const p = getPos(e);
      lastX = p.x; lastY = p.y;
    }
    function move(e){
      if(!drawing) return;
      e.preventDefault();
      const p = getPos(e);
      ctx.beginPath();
      ctx.moveTo(lastX, lastY);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();
      lastX = p.x; lastY = p.y;

      if(outputInput){
        try{
          outputInput.value = canvas.toDataURL("image/png");
        }catch(_){}
      }
    }
    function end(e){
      if(!drawing) return;
      e.preventDefault();
      drawing = false;
      if(outputInput){
        try{ outputInput.value = canvas.toDataURL("image/png"); }catch(_){}
      }
    }

    function clear(){
      const rect = canvas.getBoundingClientRect();
      ctx.clearRect(0,0,rect.width,rect.height);
      if(outputInput) outputInput.value = "";
    }

    // init
    resizeForHiDPI();
    window.addEventListener("resize", resizeForHiDPI);

    canvas.addEventListener("mousedown", start);
    canvas.addEventListener("mousemove", move);
    canvas.addEventListener("mouseup", end);
    canvas.addEventListener("mouseleave", end);

    canvas.addEventListener("touchstart", start, {passive:false});
    canvas.addEventListener("touchmove", move, {passive:false});
    canvas.addEventListener("touchend", end, {passive:false});

    if(clearBtn) clearBtn.addEventListener("click", clear);
  }

  document.addEventListener("DOMContentLoaded", function(){
    // auto find signature widgets
    const canvas = document.querySelector("[data-sig-canvas='1']");
    const out = document.querySelector("[data-sig-output='1']");
    const clearBtn = document.querySelector("[data-sig-clear='1']");
    setupCanvas(canvas, out, clearBtn);

    // If user draws, uncheck "use saved signature" automatically
    if(canvas){
      canvas.addEventListener("mousedown", ()=>{
        const chk = document.querySelector("input[name='use_saved_signature']");
        if(chk) chk.checked = false;
      });
      canvas.addEventListener("touchstart", ()=>{
        const chk = document.querySelector("input[name='use_saved_signature']");
        if(chk) chk.checked = false;
      }, {passive:true});
    }
  });
})();
