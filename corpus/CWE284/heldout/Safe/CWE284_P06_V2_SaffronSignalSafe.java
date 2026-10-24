import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SaffronSignalSafe {

    public void deleteSaffronSignalAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("SAFFRON_SIGNAL_ACCOUNT_ID");
            break;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SaffronSignalSafeSink()).applySaffronSignalDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SaffronSignalSafeSink {
    public void applySaffronSignalDeletion(String data, boolean authorized) throws SQLException {
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
