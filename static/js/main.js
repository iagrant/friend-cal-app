// Waits for the page to load before running any scripts.
document.addEventListener('DOMContentLoaded', function () {
   // --- Set Timezone Cookie ---
  if (!getCookie('timezone')) {
    const userTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    // Set the cookie to expire in one year.
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 1); 
    document.cookie = `timezone=${userTimezone};path=/;expires=${expiryDate.toUTCString()};SameSite=Lax`;
  }
  // --- Initialize Date Picker ---
  const datePicker = document.querySelector('#date-picker');
  if (datePicker) {
    flatpickr('#date-picker', {
      mode: 'multiple',
      dateFormat: 'Y-m-d',
      onChange: function (selectedDates, dateStr, instance) {
        document.getElementById('dates').value = selectedDates
          .map((date) => instance.formatDate(date, 'Y-m-d'))
          .join(',');
      },
    });
  }

  // --- Initialize Time Pickers ---
  const timeFormatIs12h = getCookie('time_format') === '12h';

  // A reusable config for our time pickers
  const timePickerConfig = {
    enableTime: true,
    noCalendar: true,
    dateFormat: 'H:i', // The format sent to the server (hidden input)
    altInput: true, // <-- ADD THIS: Creates a user-visible input
    altFormat: timeFormatIs12h ? 'h:i K' : 'H:i', // <-- ADD THIS: Format for the visible input
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