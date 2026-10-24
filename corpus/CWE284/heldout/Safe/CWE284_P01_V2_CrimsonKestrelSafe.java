import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_CrimsonKestrelSafe {

    public void deleteCrimsonKestrelAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("CRIMSON_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
