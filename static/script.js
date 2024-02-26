function redirectToPrintenPage(printerId) {
    // Construct the URL for the printen_page route
    var url = "/printen/" + printerId;
    // Redirect to the new page
    window.location.href = url;
}