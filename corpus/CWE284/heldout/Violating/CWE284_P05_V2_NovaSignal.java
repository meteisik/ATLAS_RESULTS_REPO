import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_NovaSignal {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String novaSignalAccountId;

    private boolean novaSignalAuthorized;

    private void applyNovaSignalDeletion() throws SQLException {
        String data = novaSignalAccountId;
        boolean authorized = novaSignalAuthorized;
        Connection novaSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSignal");
        try {
            PreparedStatement novaSignalDelete = novaSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaSignalDelete.setString(1, data);
            novaSignalDelete.executeUpdate();
        } finally {
            novaSignalConnection.close();
        }
    }

    public void deleteNovaSignalAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("NOVA_SIGNAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        novaSignalAccountId = data;
        novaSignalAuthorized = isAuthorized(data);
        applyNovaSignalDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
