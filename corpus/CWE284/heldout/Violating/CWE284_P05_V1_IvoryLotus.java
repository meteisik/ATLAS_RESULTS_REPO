import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_IvoryLotus {

    private String ivoryLotusAccountId;

    private boolean ivoryLotusAuthorized;

    private void applyIvoryLotusDeletion() throws SQLException {
        String data = ivoryLotusAccountId;
        boolean authorized = ivoryLotusAuthorized;
        Connection ivoryLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryLotus");
        try {
            PreparedStatement ivoryLotusDelete = ivoryLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryLotusDelete.setString(1, data);
            ivoryLotusDelete.executeUpdate();
        } finally {
            ivoryLotusConnection.close();
        }
    }

    public void deleteIvoryLotusAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_LOTUS_ACCOUNT_ID");
        ivoryLotusAccountId = data;
        ivoryLotusAuthorized = isAuthorized(data);
        applyIvoryLotusDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
