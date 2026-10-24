import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_CobaltRaven {

    public void deleteCobaltRavenAccount() throws SQLException {
        String data;
        data = System.getenv("COBALT_RAVEN_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection cobaltRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltRaven");
        try {
            PreparedStatement cobaltRavenDelete = cobaltRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltRavenDelete.setString(1, data);
            cobaltRavenDelete.executeUpdate();
        } finally {
            cobaltRavenConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
