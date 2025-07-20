document.addEventListener('DOMContentLoaded', function () {
  setTimezoneCookie();

  const datePickerInput = document.querySelector('#date-picker');
  if (datePickerInput) {
    const hiddenDatesInput = document.getElementById('dates');
    const defaultDatesAttr = hiddenDatesInput.getAttribute('data-default-dates');
    
    let defaultDates = [];
    if (defaultDatesAttr && defaultDatesAttr.trim() !== '') {
      defaultDates = defaultDatesAttr.split(',');
    }

    hiddenDatesInput.value = defaultDates.join(',');

    flatpickr(datePickerInput, {
      mode: "multiple",
      dateFormat: "Y-m-d",
      defaultDate: defaultDates,
      onChange: function(selectedDates, dateStr, instance) {
        hiddenDatesInput.value = selectedDates.map(date => instance.formatDate(date, "Y-m-d")).join(",");
      }
    });
  }

  const timeFormatIs12h = getCookie('time_format') === '12h';
  const timePickerConfig = {
    enableTime: true,
    noCalendar: true,
    dateFormat: 'H:i',
    altInput: true,
    altFormat: timeFormatIs12h ? 'h:i K' : 'H:i',
    time_24hr: !timeFormatIs12h,
  };

  const startTimePicker = document.querySelector('#start-time-picker');
  if (startTimePicker) {
    flatpickr(startTimePicker, timePickerConfig);
  }
  const endTimePicker = document.querySelector('#end-time-picker');
  if (endTimePicker) {
    flatpickr(endTimePicker, timePickerConfig);
  }

  const toggleButton = document.getElementById('time-format-toggle');
  if (toggleButton) {
    toggleButton.textContent = timeFormatIs12h ? 'Mode: 12h' : 'Mode: 24h';
  }
});

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}

function toggleTimeFormat() {
  const currentFormat = getCookie('time_format');
  const newFormat = currentFormat === '12h' ? '24h' : '12h';

  const expiryDate = new Date();
  expiryDate.setFullYear(expiryDate.getFullYear() + 1);
  document.cookie = `time_format=${newFormat};path=/;expires=${expiryDate.toUTCString()};SameSite=Lax`;

  location.reload();
}


function copyGuestLink() {
  const link = document.getElementById('guest-link');
  const copyBtn = document.getElementById('copy-btn');
  
  if (!link || !copyBtn) return;

  navigator.clipboard.writeText(link.href).then(() => {
    const originalIcon = copyBtn.textContent;
    copyBtn.textContent = '✅';
    copyBtn.disabled = true;

    setTimeout(() => {
      copyBtn.textContent = originalIcon;
      copyBtn.disabled = false;
    }, 2000);
  }).catch(err => {
    console.error('Failed to copy link: ', err);
    alert('Failed to copy link.');
  });
}

function validateCreateForm() {
  const datesInput = document.getElementById('dates');

  if (datesInput.value.trim() === '') {
    alert('Please select at least one date for the event.');
    return false;
  }

  return true;
}

function setTimezoneCookie() {
  if (!getCookie('timezone')) {
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (timezone) {
      const expiryDate = new Date();
      expiryDate.setHours(expiryDate.getHours() + 1);
      document.cookie = `timezone=${timezone};path=/;expires=${expiryDate.toUTCString()};SameSite=Lax`;
    }
  }
}