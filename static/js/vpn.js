function removeDomain(domain) {
    if (confirm('Точно удалить ' + domain + ' из прямых маршрутов?')) {
        fetch('/vpn/remove', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain: domain})
        }).then(() => location.reload());
    }
}