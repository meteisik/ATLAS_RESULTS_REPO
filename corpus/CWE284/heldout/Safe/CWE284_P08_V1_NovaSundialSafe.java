import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_NovaSundialSafe {

    public void deleteNovaSundialAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_SUNDIAL_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_NovaSundialSafeSink()).applyNovaSundialDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_NovaSundialSafeSink {
    public void applyNovaSundialDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection novaSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSundial");
        try {
            PreparedStatement novaSundialDelete = novaSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaSundialDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                novaSundialDelete.executeUpdate();
            }
        } finally {
            novaSundialConnection.close();
        }
    }
}
