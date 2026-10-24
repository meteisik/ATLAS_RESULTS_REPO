import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SaffronSignalSafe {

    public static String data;

    public static boolean authorized;

    public void deleteSaffronSignalAccount() throws SQLException {
        data = System.getenv("SAFFRON_SIGNAL_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SaffronSignalSafeSink()).applySaffronSignalDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SaffronSignalSafeSink {
    public void applySaffronSignalDeletion() throws SQLException {
        String data = CWE284_P10_V1_SaffronSignalSafe.data;
        boolean authorized = CWE284_P10_V1_SaffronSignalSafe.authorized;
        Connection saffronSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSignal");
        try {
            PreparedStatement saffronSignalDelete = saffronSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronSignalDelete.setString(1, data);
            if (authorized) {
                saffronSignalDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronSignalConnection.close();
        }
    }
}
