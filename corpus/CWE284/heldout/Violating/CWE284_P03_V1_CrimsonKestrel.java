import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CrimsonKestrel {

    private void applyCrimsonKestrelDeletion(String data, boolean authorized) throws SQLException {
        Connection crimsonKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonKestrel");
        try {
            PreparedStatement crimsonKestrelDelete = crimsonKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonKestrelDelete.setString(1, data);
            if (authorized) {
                crimsonKestrelDelete.executeUpdate();
            }
        } finally {
            crimsonKestrelConnection.close();
        }
    }

    public void deleteCrimsonKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_KESTREL_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyCrimsonKestrelDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
