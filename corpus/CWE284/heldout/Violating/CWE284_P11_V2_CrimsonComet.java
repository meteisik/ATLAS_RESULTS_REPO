import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_CrimsonComet {
    private static int privateFive = 5;

    public void deleteCrimsonCometAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("CRIMSON_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_CrimsonCometSink()).applyCrimsonCometDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_CrimsonCometSink {
    public void applyCrimsonCometDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection crimsonCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonComet");
        try {
            PreparedStatement crimsonCometDelete = crimsonCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonCometDelete.setString(1, data);
            if (authorized) {
                crimsonCometDelete.executeUpdate();
            }
        } finally {
            crimsonCometConnection.close();
        }
    }
}
