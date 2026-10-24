import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_IvoryLotusSafe {

    private void applyIvoryLotusDeletion(String data, boolean authorized) throws SQLException {
        Connection ivoryLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryLotus");
        try {
            PreparedStatement ivoryLotusDelete = ivoryLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryLotusDelete.setString(1, data);
            if (authorized) {
                ivoryLotusDelete.executeUpdate();
            }
        } finally {
            ivoryLotusConnection.close();
        }
    }

    public void deleteIvoryLotusAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_LOTUS_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyIvoryLotusDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
