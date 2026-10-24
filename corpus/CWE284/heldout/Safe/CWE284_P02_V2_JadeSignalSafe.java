import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_JadeSignalSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteJadeSignalAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = System.getenv("JADE_SIGNAL_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
