import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_NovaSignal {

    public void deleteNovaSignalAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_SIGNAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_NovaSignalSink()).applyNovaSignalDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_NovaSignalSink {
    public void applyNovaSignalDeletion(String data, boolean authorized) throws SQLException {
        Connection novaSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSignal");
        try {
            PreparedStatement novaSignalDelete = novaSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaSignalDelete.setString(1, data);
            novaSignalDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            novaSignalConnection.close();
        }
    }
}
