import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_NovaPrismSafe {

    public void deleteNovaPrismAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_PRISM_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_NovaPrismSafeSink()).applyNovaPrismDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_NovaPrismSafeSink {
    public void applyNovaPrismDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection novaPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaPrism");
        try {
            PreparedStatement novaPrismDelete = novaPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaPrismDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                novaPrismDelete.executeUpdate();
            }
        } finally {
            novaPrismConnection.close();
        }
    }
}
