import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_NovaSignalSafe {

    private boolean checkNovaSignalAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteNovaSignalAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("NOVA_SIGNAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkNovaSignalAccess(data);
        Connection novaSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSignal");
        try {
            PreparedStatement novaSignalDelete = novaSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaSignalDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                novaSignalDelete.executeUpdate();
            }
        } finally {
            novaSignalConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
