struct buffer_and_size {
    char* data;
    size_t len;
};

void http_get
(
    CURL* curl,
    const char* url,
    struct buffer_and_size* header,
    struct buffer_and_size* body,
    struct curl_slist* request_headers,
    char* request_body
);
