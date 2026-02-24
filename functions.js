// fonction success
success=(result)=>{
    return {
        status:'success',
        result:result
           }
            };

// fonction error
error=(message)=>{
        return {
        status:'error',
        message:message
           }
            };
exports.success=success;
exports.error=error;