document.addEventListener('DOMContentLoaded', function () {
  // --- Consolidated Date Picker Initialization ---
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

  // --- Initialize Time Pickers ---
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

  // --- Update Toggle Button Text ---
  const toggleButton = document.getElementById('time-format-toggle');
  if (toggleButton) {
    toggleButton.textContent = timeFormatIs12h ? 'Mode: 12h' : 'Mode: 24h';
  }
});

// Helper function to get a specific cookie by name
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

// Add this new function to static/js/main.js

function copyGuestLink() {
  // Find the link and the button by their IDs
  const link = document.getElementById('guest-link');
  const copyBtn = document.getElementById('copy-btn');
  
  if (!link || !copyBtn) return;

  // Use the Clipboard API to copy the link's href value
  navigator.clipboard.writeText(link.href).then(() => {
    // On success, give the user feedback
    const originalIcon = copyBtn.textContent;
    copyBtn.textContent = '✅';
    copyBtn.disabled = true;

    // Change it back after 2 seconds
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
  // Find the hidden input that holds the dates.
  const datesInput = document.getElementById('dates');

  // Check if its value is empty.
  if (datesInput.value.trim() === '') {
    // If it's empty, show an alert message.
    alert('Please select at least one date for the event.');
    // And cancel the form submission.
    return false;
  }

  // If dates are present, allow the form to submit.
  return true;
}