import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_RuneLotusSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteRuneLotusAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("RUNE_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_RuneLotusSafeChecker()).isAuthorized(data);
        Connection runeLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLotus");
        try {
            PreparedStatement runeLotusDelete = runeLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLotusDelete.setString(1, data);
            if (authorized) {
                runeLotusDelete.executeUpdate();
            }
        } finally {
            runeLotusConnection.close();
        }
    }
}

class CWE284_P07_V2_RuneLotusSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
