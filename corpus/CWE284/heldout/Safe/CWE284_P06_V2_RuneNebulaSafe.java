import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_RuneNebulaSafe {
    private static boolean privateTrue = true;

    public void deleteRuneNebulaAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("RUNE_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_RuneNebulaSafeSink()).applyRuneNebulaDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_RuneNebulaSafeSink {
    public void applyRuneNebulaDeletion(String data, boolean authorized) throws SQLException {
        Connection runeNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeNebula");
        try {
            PreparedStatement runeNebulaDelete = runeNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeNebulaDelete.setString(1, data);
            if (authorized) {
                runeNebulaDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeNebulaConnection.close();
        }
    }
}
