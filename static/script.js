document.addEventListener('DOMContentLoaded', function () {
	const textarea = document.querySelector('textarea[name="descricao"]');
	const maxChars = 250;

	// Cria o contador se não existir
	let counter = document.getElementById('descricao-counter');
	if (!counter && textarea) {
		counter = document.createElement('div');
		counter.id = 'descricao-counter';
		counter.style.fontSize = '0.9em';
		// counter.style.color = '#444';
		counter.style.textAlign = 'right';
		textarea.parentNode.appendChild(counter);
	}

	function updateCounter() {
		const restante = maxChars - textarea.value.length;
		counter.textContent = `Caracteres restantes: ${restante}`;
		if (textarea.value.length > maxChars) {
			textarea.value = textarea.value.substring(0, maxChars);
			counter.textContent = 'Caracteres restantes: 0';
		}
	}

	if (textarea) {
		textarea.setAttribute('maxlength', maxChars);
		textarea.addEventListener('input', updateCounter);
		updateCounter();
	}
});
