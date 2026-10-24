import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_OnyxLotus {
    private static boolean privateTrue = true;

    private boolean checkOnyxLotusAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteOnyxLotusAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("ONYX_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkOnyxLotusAccess(data);
        Connection onyxLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLotus");
        try {
            PreparedStatement onyxLotusDelete = onyxLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxLotusDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                onyxLotusDelete.executeUpdate();
            }
        } finally {
            onyxLotusConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
