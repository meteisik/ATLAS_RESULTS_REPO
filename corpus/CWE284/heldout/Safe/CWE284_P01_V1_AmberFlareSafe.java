import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AmberFlareSafe {

    public void deleteAmberFlareAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_FLARE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection amberFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberFlare");
        try {
            PreparedStatement amberFlareDelete = amberFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberFlareDelete.setString(1, data);
            if (authorized) {
                amberFlareDelete.executeUpdate();
            }
        } finally {
            amberFlareConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
