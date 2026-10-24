import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CobaltRaven {

    private void applyCobaltRavenDeletion(String data, boolean authorized) throws SQLException {
        Connection cobaltRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltRaven");
        try {
            PreparedStatement cobaltRavenDelete = cobaltRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltRavenDelete.setString(1, data);
            if (authorized) {
                cobaltRavenDelete.executeUpdate();
            }
        } finally {
            cobaltRavenConnection.close();
        }
    }

    public void deleteCobaltRavenAccount() throws SQLException {
        String data;
        data = System.getenv("COBALT_RAVEN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyCobaltRavenDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
