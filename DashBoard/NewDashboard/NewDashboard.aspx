<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="NewDashboard.aspx.cs" Inherits="WebFormsClient.DashBoard.NewDashboard.NewDashboard" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
        <div>
           
                <h1>Secure Page, logged in as <%= User.Identity.Name %></h1>
                <ul>
                    <% foreach (var claim in ((System.Security.Claims.ClaimsPrincipal)User).Claims)
                        { %>
                    <li><%: claim.Type + ", " + claim.Value %></li>
                    <%} %>
                </ul>
           
        </div>
    </form>
</body>
</html>
