using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWTApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestTokenController : ControllerBase
    {
        [Authorize]
        [HttpGet("GetMessage")]
        public IActionResult GetMessages()
        {
            return Ok("Test Token Please!!");
        }
    }
}
