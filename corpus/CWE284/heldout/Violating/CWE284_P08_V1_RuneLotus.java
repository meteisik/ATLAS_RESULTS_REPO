import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_RuneLotus {

    public void deleteRuneLotusAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_LOTUS_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_RuneLotusSink()).applyRuneLotusDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_RuneLotusSink {
    public void applyRuneLotusDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection runeLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLotus");
        try {
            PreparedStatement runeLotusDelete = runeLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLotusDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                runeLotusDelete.executeUpdate();
            }
        } finally {
            runeLotusConnection.close();
        }
    }
}
