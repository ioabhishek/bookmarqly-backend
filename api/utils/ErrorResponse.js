class ErrorResponse {
  constructor(statusCode, message = "Success") {
    this.statusCode = statusCode
    this.message = message
    this.success = statusCode < 400
  }
}

export { ErrorResponse }
