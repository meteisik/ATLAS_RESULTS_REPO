import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CrimsonRavenSafe {

    private void applyCrimsonRavenDeletion(String data, boolean authorized) throws SQLException {
        Connection crimsonRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonRaven");
        try {
            PreparedStatement crimsonRavenDelete = crimsonRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonRavenDelete.setString(1, data);
            if (authorized) {
                crimsonRavenDelete.executeUpdate();
            }
        } finally {
            crimsonRavenConnection.close();
        }
    }

    public void deleteCrimsonRavenAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_RAVEN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyCrimsonRavenDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
