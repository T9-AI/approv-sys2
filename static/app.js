(function(){
  const form = document.getElementById('reqForm');
  const today = new Date().toISOString().split('T')[0];

  function enforceDates(){
    document.querySelectorAll('.js-date').forEach(el => {
      if(!el.value){
        el.value = today;
      }
      el.setAttribute('min', today);
    });
  }

  function lockSection(prefix, fields){
    const yes = document.querySelector(`input[name='${prefix}_yes']`);
    const no = document.querySelector(`input[name='${prefix}_no']`);
    const inputs = fields.map(sel => document.querySelector(sel)).filter(Boolean);
    function apply(){
      if(no && no.checked){
        inputs.forEach(el => {
          el.value = 'N/A';
          el.readOnly = true;
          el.disabled = true;
          el.classList.add('locked');
        });
      } else if(yes && yes.checked){
        inputs.forEach(el => {
          if(el.value === 'N/A'){ el.value = ''; }
          el.readOnly = false;
          el.disabled = false;
          el.classList.remove('locked');
        });
      } else {
        inputs.forEach(el => {
          el.readOnly = true;
          el.disabled = true;
          el.classList.add('locked');
        });
      }
    }
    yes && yes.addEventListener('change', () => {
      if(yes.checked && no){ no.checked = false; }
      apply();
    });
    no && no.addEventListener('change', () => {
      if(no.checked && yes){ yes.checked = false; }
      apply();
    });
    apply();
  }

  function validateRoutes(evt){
    if(!form) return;
    const rows = document.querySelectorAll('[data-manager-route]');
    let toCount = 0;
    rows.forEach(row => {
      const mid = row.dataset.managerRoute;
      const to = row.querySelector(`input[name='route_${mid}'][value='to']`);
      const cc = row.querySelector(`input[name='route_${mid}'][value='cc']`);
      if(to && to.checked){ toCount++; }
      if(to && cc && to.checked && cc.checked){
        evt.preventDefault();
        alert('Manager cannot be both TO and CC.');
      }
    });
    if(toCount === 0){
      evt.preventDefault();
      alert('Select at least one TO manager.');
    }
    document.querySelectorAll('.locked').forEach(el => { el.disabled = false; });
  }

  if(form){
    enforceDates();
    lockSection('sec2', ['input[name="sec2_boq"]','input[name="sec2_proposed"]','input[name="sec2_variation"]','textarea[name="sec2_notes"]']);
    lockSection('sec3', ['textarea[name="sec3_notes"]']);
    lockSection('sec4', ['textarea[name="sec4_notes"]']);
    form.addEventListener('submit', validateRoutes);
  }
})();
