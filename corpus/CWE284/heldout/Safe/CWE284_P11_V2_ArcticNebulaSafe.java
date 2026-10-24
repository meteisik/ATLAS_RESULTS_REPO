import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_ArcticNebulaSafe {

    public void deleteArcticNebulaAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("ARCTIC_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_ArcticNebulaSafeSink()).applyArcticNebulaDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_ArcticNebulaSafeSink {
    public void applyArcticNebulaDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection arcticNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticNebula");
        try {
            PreparedStatement arcticNebulaDelete = arcticNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticNebulaDelete.setString(1, data);
            if (authorized) {
                arcticNebulaDelete.executeUpdate();
            }
        } finally {
            arcticNebulaConnection.close();
        }
    }
}
