import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_OnyxLotus {
    private static int privateFive = 5;

    private String onyxLotusAccountId;

    private boolean onyxLotusAuthorized;

    private void applyOnyxLotusDeletion() throws SQLException {
        String data = onyxLotusAccountId;
        boolean authorized = onyxLotusAuthorized;
        Connection onyxLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLotus");
        try {
            PreparedStatement onyxLotusDelete = onyxLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxLotusDelete.setString(1, data);
            onyxLotusDelete.executeUpdate();
        } finally {
            onyxLotusConnection.close();
        }
    }

    public void deleteOnyxLotusAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ONYX_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        onyxLotusAccountId = data;
        onyxLotusAuthorized = isAuthorized(data);
        applyOnyxLotusDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
