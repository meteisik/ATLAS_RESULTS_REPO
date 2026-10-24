import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_JadeSignalSafe {

    public void deleteJadeSignalAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_SIGNAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_JadeSignalSafeSink()).applyJadeSignalDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_JadeSignalSafeSink {
    public void applyJadeSignalDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeSignal");
        try {
            PreparedStatement jadeSignalDelete = jadeSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeSignalDelete.setString(1, data);
            if (authorized) {
                jadeSignalDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            jadeSignalConnection.close();
        }
    }
}
