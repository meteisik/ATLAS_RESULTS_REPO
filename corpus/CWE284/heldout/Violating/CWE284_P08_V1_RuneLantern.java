import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_RuneLantern {

    public void deleteRuneLanternAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_LANTERN_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_RuneLanternSink()).applyRuneLanternDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_RuneLanternSink {
    public void applyRuneLanternDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection runeLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLantern");
        try {
            PreparedStatement runeLanternDelete = runeLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLanternDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                runeLanternDelete.executeUpdate();
            }
        } finally {
            runeLanternConnection.close();
        }
    }
}
