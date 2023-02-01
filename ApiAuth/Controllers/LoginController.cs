using ApiAuth.Model;
using ApiAuth.Repositories;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace ApiAuth.Controllers
{
    [Route("api")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<dynamic>> AuthenticateAsync([FromBody] User model)
        {
            //Recuperar o Usuario
            var user = UserRepository.Get(model.Username, model.Password);

            //Verifica se o usuario existe
            if (user == null)
            {
                return NotFound(new { message = "Usuario ou senha inválidos" });
            }

            //Gera o token
            var token = TokenService.GerarToken(user);
            var refreshToken = TokenService.GerarRefreshToken();
            TokenService.SalvarRefreshToken(model.Username, refreshToken);

            //oculta a senha
            user.Password = "";
            return new
            {
                user = user,
                token = token,
                refreshToken = refreshToken
            };
        }

        [HttpPost]
        [Route("refresh")]
        public IActionResult Refresh(string token, string refreshToken)
        {
            var principal = TokenService.GetPrincipalFromExpiredToken(token);
            var username = principal.Identity.Name;
            var refreshTokenSalvo = TokenService.GetRefreshToken(username);

            if (refreshTokenSalvo != refreshToken)
                throw new SecurityTokenException("Invalid Refresh token");

            var novoJwtToken = TokenService.GerarToken(principal.Claims);
            var newRefreshToken = TokenService.GerarRefreshToken();
            TokenService.DeletarRefreshToken(username, refreshToken);
            TokenService.SalvarRefreshToken(username, newRefreshToken);

            return new ObjectResult(new
            {
                token = novoJwtToken,
                refreshToken = newRefreshToken
            });

        }
    }
}
