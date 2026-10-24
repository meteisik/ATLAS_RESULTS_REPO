import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_RuneLotusSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteRuneLotusAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("RUNE_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_RuneLotusSafeSink()).applyRuneLotusDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_RuneLotusSafeSink {
    public void applyRuneLotusDeletion(String data, boolean authorized) throws SQLException {
        Connection runeLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLotus");
        try {
            PreparedStatement runeLotusDelete = runeLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLotusDelete.setString(1, data);
            if (authorized) {
                runeLotusDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeLotusConnection.close();
        }
    }
}
