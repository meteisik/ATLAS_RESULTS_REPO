import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_NovaSignalSafe {

    public void deleteNovaSignalAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_SIGNAL_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_NovaSignalSafeSink()).applyNovaSignalDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_NovaSignalSafeSink {
    public void applyNovaSignalDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
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
}
