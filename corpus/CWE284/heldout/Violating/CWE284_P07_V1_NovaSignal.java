import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_NovaSignal {

    public void deleteNovaSignalAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_SIGNAL_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_NovaSignalChecker()).isAuthorized(requester);
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
}

class CWE284_P07_V1_NovaSignalChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
