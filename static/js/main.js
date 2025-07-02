document.addEventListener('DOMContentLoaded', function () {
  // Find the date-picker element on the page.
  const datePicker = document.querySelector('#date-picker');

  // If the element exists, initialize flatpickr on it.
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
});