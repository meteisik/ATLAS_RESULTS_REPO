import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_IvoryLotus {

    private boolean checkIvoryLotusAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteIvoryLotusAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_LOTUS_ACCOUNT_ID");
        boolean authorized = checkIvoryLotusAccess(data);
        Connection ivoryLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryLotus");
        try {
            PreparedStatement ivoryLotusDelete = ivoryLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryLotusDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                ivoryLotusDelete.executeUpdate();
            }
        } finally {
            ivoryLotusConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
