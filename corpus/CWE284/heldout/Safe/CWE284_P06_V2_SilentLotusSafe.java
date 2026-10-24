import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SilentLotusSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteSilentLotusAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SILENT_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SilentLotusSafeSink()).applySilentLotusDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SilentLotusSafeSink {
    public void applySilentLotusDeletion(String data, boolean authorized) throws SQLException {
        Connection silentLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLotus");
        try {
            PreparedStatement silentLotusDelete = silentLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentLotusDelete.setString(1, data);
            if (authorized) {
                silentLotusDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            silentLotusConnection.close();
        }
    }
}
