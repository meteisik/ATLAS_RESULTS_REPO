import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_CobaltKestrelSafe {

    public void deleteCobaltKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("COBALT_KESTREL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection cobaltKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltKestrel");
        try {
            PreparedStatement cobaltKestrelDelete = cobaltKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltKestrelDelete.setString(1, data);
            if (authorized) {
                cobaltKestrelDelete.executeUpdate();
            }
        } finally {
            cobaltKestrelConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
