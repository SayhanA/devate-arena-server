const catchAsyncError = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next))
            .catch((error) => {
                // Log the error for debugging purposes
                console.error("Async Error:", error);
                
                // Pass the error to the next middleware
                next(error);
            });
    }
}

module.exports = catchAsyncError;