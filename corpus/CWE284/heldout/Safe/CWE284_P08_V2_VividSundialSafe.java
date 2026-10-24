import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_VividSundialSafe {

    public void deleteVividSundialAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("VIVID_SUNDIAL_ACCOUNT_ID");
            break;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_VividSundialSafeSink()).applyVividSundialDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_VividSundialSafeSink {
    public void applyVividSundialDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection vividSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSundial");
        try {
            PreparedStatement vividSundialDelete = vividSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividSundialDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                vividSundialDelete.executeUpdate();
            }
        } finally {
            vividSundialConnection.close();
        }
    }
}
