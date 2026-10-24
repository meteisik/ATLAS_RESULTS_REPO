import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_RuneNebulaSafe {
    private static int privateFive = 5;

    public void deleteRuneNebulaAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("RUNE_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_RuneNebulaSafeChecker()).isAuthorized(data);
        Connection runeNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeNebula");
        try {
            PreparedStatement runeNebulaDelete = runeNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeNebulaDelete.setString(1, data);
            if (authorized) {
                runeNebulaDelete.executeUpdate();
            }
        } finally {
            runeNebulaConnection.close();
        }
    }
}

class CWE284_P07_V2_RuneNebulaSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
