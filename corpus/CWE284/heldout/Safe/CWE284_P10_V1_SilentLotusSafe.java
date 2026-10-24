import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SilentLotusSafe {

    public static String data;

    public static boolean authorized;

    public void deleteSilentLotusAccount() throws SQLException {
        data = System.getenv("SILENT_LOTUS_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SilentLotusSafeSink()).applySilentLotusDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SilentLotusSafeSink {
    public void applySilentLotusDeletion() throws SQLException {
        String data = CWE284_P10_V1_SilentLotusSafe.data;
        boolean authorized = CWE284_P10_V1_SilentLotusSafe.authorized;
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
