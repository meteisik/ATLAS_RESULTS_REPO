import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_MosaicNebulaSafe {
    private static int privateFive = 5;

    private void applyMosaicNebulaDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicNebula");
        try {
            PreparedStatement mosaicNebulaDelete = mosaicNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicNebulaDelete.setString(1, data);
            if (authorized) {
                mosaicNebulaDelete.executeUpdate();
            }
        } finally {
            mosaicNebulaConnection.close();
        }
    }

    public void deleteMosaicNebulaAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("MOSAIC_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyMosaicNebulaDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
