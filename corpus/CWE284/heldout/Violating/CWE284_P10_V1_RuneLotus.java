import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_RuneLotus {

    public static String data;

    public static boolean authorized;

    public void deleteRuneLotusAccount() throws SQLException {
        data = System.getenv("RUNE_LOTUS_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_RuneLotusSink()).applyRuneLotusDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_RuneLotusSink {
    public void applyRuneLotusDeletion() throws SQLException {
        String data = CWE284_P10_V1_RuneLotus.data;
        boolean authorized = CWE284_P10_V1_RuneLotus.authorized;
        Connection runeLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLotus");
        try {
            PreparedStatement runeLotusDelete = runeLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLotusDelete.setString(1, data);
            runeLotusDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeLotusConnection.close();
        }
    }
}
