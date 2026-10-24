import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_RuneLantern {

    public static String data;

    public static boolean authorized;

    public void deleteRuneLanternAccount() throws SQLException {
        data = System.getenv("RUNE_LANTERN_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_RuneLanternSink()).applyRuneLanternDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_RuneLanternSink {
    public void applyRuneLanternDeletion() throws SQLException {
        String data = CWE284_P10_V1_RuneLantern.data;
        boolean authorized = CWE284_P10_V1_RuneLantern.authorized;
        Connection runeLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLantern");
        try {
            PreparedStatement runeLanternDelete = runeLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLanternDelete.setString(1, data);
            runeLanternDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeLanternConnection.close();
        }
    }
}
