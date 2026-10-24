import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_NovaSignalSafe {

    private void applyNovaSignalDeletion(String data, boolean authorized) throws SQLException {
        Connection novaSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSignal");
        try {
            PreparedStatement novaSignalDelete = novaSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaSignalDelete.setString(1, data);
            if (authorized) {
                novaSignalDelete.executeUpdate();
            }
        } finally {
            novaSignalConnection.close();
        }
    }

    public void deleteNovaSignalAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("NOVA_SIGNAL_ACCOUNT_ID");
            break;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyNovaSignalDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
